#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-d-android.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

bash "${ROOT}/scripts/build-phase-d-android-reach-evidence.sh" \
  --output-json "${TMP_DIR}/android.json" \
  --output-markdown "${TMP_DIR}/android.md"

grep -q '"rust_jni_core_compiles": true' "${TMP_DIR}/android.json"
grep -q '"vpnservice_basic_flow_proven": false' "${TMP_DIR}/android.json"
grep -q '"production_android_claimed": false' "${TMP_DIR}/android.json"
grep -q 'Phase D Android Reach Evidence' "${TMP_DIR}/android.md"

cat >"${TMP_DIR}/vpn-pass.json" <<'JSON'
{
  "status": "PASS",
  "feature": "android_vpnservice_basic_flow",
  "platform": "Android",
  "scope": "vpnservice_poc",
  "vpnservice_basic_flow_proven": true,
  "tun_packet_flow_observed": true,
  "relay_session_succeeded": true,
  "production_android_claimed": false
}
JSON

bash "${ROOT}/scripts/build-phase-d-android-reach-evidence.sh" \
  --output-json "${TMP_DIR}/android-vpn.json" \
  --vpnservice-flow-json "${TMP_DIR}/vpn-pass.json"

grep -q '"vpnservice_basic_flow_proven": true' "${TMP_DIR}/android-vpn.json"

cat >"${TMP_DIR}/weak-vpn.json" <<'JSON'
{
  "status": "PASS",
  "vpnservice_basic_flow_proven": true
}
JSON

bash "${ROOT}/scripts/build-phase-d-android-reach-evidence.sh" \
  --output-json "${TMP_DIR}/android-weak-vpn.json" \
  --vpnservice-flow-json "${TMP_DIR}/weak-vpn.json"

grep -q '"vpnservice_basic_flow_proven": false' "${TMP_DIR}/android-weak-vpn.json"

if bash "${ROOT}/scripts/build-phase-d-android-reach-evidence.sh" \
  --output-json "${TMP_DIR}/android-prod.json" \
  --production-claim; then
  echo "expected production Android claim to fail evidence builder" >&2
  exit 1
fi
grep -q '"production_android_claimed": true' "${TMP_DIR}/android-prod.json"

echo "ok"
