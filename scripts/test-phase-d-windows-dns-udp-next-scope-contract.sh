#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/windows/run-wfp-controlled-dns-udp-proof.ps1"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-windows-dns-udp.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

grep -q "windows_wfp_controlled_dns_udp_next_scope" "${SCRIPT}"
grep -q "aegis-winctl wfp udp-feasibility" "${SCRIPT}"
grep -q "ALE_CONNECT_REDIRECT_V4" "${SCRIPT}"
grep -q "IPPROTO_TCP" "${SCRIPT}"
grep -q "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER" "${SCRIPT}"
grep -q "UDP_CAPTURE_REQUIRES_CALLOUT_DRIVER" "${SCRIPT}"
grep -q "controlled_target_only" "${SCRIPT}"
grep -q "dns_capture_claimed.*false" "${SCRIPT}"
grep -q "udp_capture_claimed.*false" "${SCRIPT}"
grep -q "ipv6_capture_claimed.*false" "${SCRIPT}"
grep -q "broad_capture_claim.*not_claimed" "${SCRIPT}"

mkdir -p "${TMP_DIR}/next-scope"
cat >"${TMP_DIR}/next-scope/result.json" <<'JSON'
{
  "feature": "windows_wfp_controlled_dns_udp_next_scope",
  "platform": "Windows",
  "scope": "controlled_dns_udp_only",
  "status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER",
  "verdict": "BLOCKED",
  "dns_udp_next_scope_status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER",
  "controlled_target_only": true,
  "controlled_udp_or_dns_captured": false,
  "cleanup": "PASS",
  "dns_capture_claimed": false,
  "udp_capture_claimed": false,
  "ipv6_capture_claimed": false,
  "broad_capture_claim": "not_claimed"
}
JSON
grep -q '"dns_udp_next_scope_status": "UDP_CAPTURE_REQUIRES_NEW_WFP_LAYER"' "${TMP_DIR}/next-scope/result.json"

echo "ok"
