#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-ne.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

if bash "${ROOT}/scripts/macos/run-networkextension-system-wide-proof.sh" \
  "${TMP_DIR}/artifact" \
  --expected-egress "198.51.100.229"; then
  echo "expected non-macOS or incomplete NetworkExtension proof to block" >&2
  exit 1
fi

grep -q '"status": "BLOCKED"' "${TMP_DIR}/artifact/result.json"
grep -q '"feature": "macos_networkextension_system_wide_proof"' "${TMP_DIR}/artifact/result.json"
grep -q '"network_extension_system_wide_proven": false' "${TMP_DIR}/artifact/result.json"
grep -q '"packet_tunnel_runtime_proven": false' "${TMP_DIR}/artifact/result.json"
grep -q '"relay_session_succeeded": false' "${TMP_DIR}/artifact/result.json"

mkdir -p "${TMP_DIR}/pf" "${TMP_DIR}/foreground" "${TMP_DIR}/launchdaemon"
cat >"${TMP_DIR}/pf/result.json" <<'JSON'
{
  "verdict": "PASS",
  "live_claim": "PF_RULE_APPLY_AND_CLEANUP_ONLY",
  "runtime_traffic_proof": false,
  "apply": {"command_result": "PASS"},
  "cleanup": {"result": "PASS", "aegis_rules_gone": true}
}
JSON
cat >"${TMP_DIR}/foreground/result.json" <<'JSON'
{
  "verdict": "PASS",
  "socks_public_ipv4": "198.51.100.229",
  "socks_expected_ipv4": "198.51.100.229",
  "runtime_events_jsonl_valid": true
}
JSON
cat >"${TMP_DIR}/launchdaemon/result.json" <<'JSON'
{
  "verdict": "PASS",
  "socks_public_ipv4": "198.51.100.229",
  "socks_expected_ipv4": "198.51.100.229",
  "runtime_events_jsonl_valid": true
}
JSON

if bash "${ROOT}/scripts/build-phase-d-macos-reach-evidence.sh" \
  --pf-artifact "${TMP_DIR}/pf" \
  --foreground-socks-artifact "${TMP_DIR}/foreground" \
  --launchdaemon-socks-artifact "${TMP_DIR}/launchdaemon" \
  --network-extension-artifact "${TMP_DIR}/artifact" \
  --output-json "${TMP_DIR}/macos-reach.json"; then
  echo "expected blocked NetworkExtension artifact to keep macOS reach non-exit" >&2
  exit 1
fi

grep -q '"network_extension_system_wide_proven": false' "${TMP_DIR}/macos-reach.json"

echo "ok"
