#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-android-vpnservice.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

if bash "${ROOT}/scripts/android/run-vpnservice-basic-flow-proof.sh" \
  "${TMP_DIR}/artifact" \
  --adb "${TMP_DIR}/missing-adb" \
  --expected-egress "198.51.100.229"; then
  echo "expected missing adb to keep Android VpnService proof blocked" >&2
  exit 1
fi

grep -q '"status": "BLOCKED"' "${TMP_DIR}/artifact/result.json"
grep -q '"feature": "android_vpnservice_basic_flow"' "${TMP_DIR}/artifact/result.json"
grep -q '"vpnservice_basic_flow_proven": false' "${TMP_DIR}/artifact/result.json"
grep -q '"tun_packet_flow_observed": false' "${TMP_DIR}/artifact/result.json"
grep -q '"relay_session_succeeded": false' "${TMP_DIR}/artifact/result.json"
grep -q '"blocker": "adb_not_found"' "${TMP_DIR}/artifact/result.json"

bash "${ROOT}/scripts/build-phase-d-android-reach-evidence.sh" \
  --output-json "${TMP_DIR}/android-reach.json" \
  --vpnservice-flow-json "${TMP_DIR}/artifact/result.json"

grep -q '"vpnservice_basic_flow_proven": false' "${TMP_DIR}/android-reach.json"

echo "ok"
