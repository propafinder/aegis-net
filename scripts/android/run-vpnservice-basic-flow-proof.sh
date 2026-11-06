#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: scripts/android/run-vpnservice-basic-flow-proof.sh <artifact-dir> [options]

Options:
  --adb <path>             adb binary to use (default: adb)
  --package <package>      Android package to inspect (default: org.aegis.android)
  --expected-egress <ip>   expected relay egress IP for a future PASS proof

This runner is intentionally conservative. It creates a Phase D Android
VpnService proof artifact, but it reports BLOCKED unless a real Android
runtime/device/app proof path exists. It never fabricates
vpnservice_basic_flow_proven=true.
EOF
}

artifact_dir="${1:-}"
if [[ -z "${artifact_dir}" || "${artifact_dir}" == "--help" || "${artifact_dir}" == "-h" ]]; then
  usage
  exit 2
fi
shift || true

adb_bin="adb"
package_name="org.aegis.android"
expected_egress="${AEGIS_EXPECTED_RELAY_EGRESS:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --adb)
      adb_bin="${2:?missing --adb value}"
      shift 2
      ;;
    --package)
      package_name="${2:?missing --package value}"
      shift 2
      ;;
    --expected-egress)
      expected_egress="${2:?missing --expected-egress value}"
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
  local cleanup="$3"
  cat >"${artifact_dir}/result.json" <<EOF
{
  "status": "$(json_escape "${status}")",
  "feature": "android_vpnservice_basic_flow",
  "platform": "Android",
  "scope": "vpnservice_poc",
  "package": "$(json_escape "${package_name}")",
  "expected_relay_egress_ip": "$(json_escape "${expected_egress}")",
  "vpnservice_basic_flow_proven": false,
  "tun_packet_flow_observed": false,
  "relay_session_succeeded": false,
  "production_android_claimed": false,
  "cleanup": "$(json_escape "${cleanup}")",
  "blocker": "$(json_escape "${blocker}")"
}
EOF
}

{
  echo "artifact_dir=${artifact_dir}"
  echo "adb=${adb_bin}"
  echo "package=${package_name}"
  echo "expected_egress=${expected_egress}"
  echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"${artifact_dir}/commands.txt"

{
  uname -a || true
  echo "PATH=${PATH}"
} >"${artifact_dir}/environment.txt"

if ! command -v "${adb_bin}" >/dev/null 2>&1; then
  echo "adb not found: ${adb_bin}" >"${artifact_dir}/adb.log"
  write_result "BLOCKED" "adb_not_found" "NOT_STARTED"
  exit 2
fi

if ! "${adb_bin}" start-server >"${artifact_dir}/adb-start.log" 2>&1; then
  write_result "BLOCKED" "adb_start_failed" "NOT_STARTED"
  exit 2
fi

"${adb_bin}" devices >"${artifact_dir}/adb-devices.log" 2>&1 || true
if ! awk 'NR > 1 && $2 == "device" { found = 1 } END { exit found ? 0 : 1 }' \
  "${artifact_dir}/adb-devices.log"; then
  write_result "BLOCKED" "android_device_not_connected" "NOT_STARTED"
  exit 2
fi

if ! "${adb_bin}" shell pm path "${package_name}" >"${artifact_dir}/package.log" 2>&1; then
  write_result "BLOCKED" "aegis_android_package_missing" "NOT_STARTED"
  exit 2
fi

cat >"${artifact_dir}/README.md" <<EOF
# Android VpnService Basic Flow Proof

This artifact reached a connected Android device and found package
\`${package_name}\`, but the app-side VpnService runtime proof harness is not
implemented in this repository yet.

The artifact is intentionally BLOCKED and must not be counted as Phase D PASS.
EOF

write_result "BLOCKED" "android_vpnservice_runtime_harness_not_implemented" "NOT_STARTED"
exit 2
