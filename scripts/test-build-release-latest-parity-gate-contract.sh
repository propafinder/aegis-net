#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

for name in server client negative; do
  mkdir -p "${TMP_DIR}/${name}"
done

cat >"${TMP_DIR}/server/result.json" <<'JSON'
{
  "schema_version": 1,
  "verdict": "PASS",
  "latest_tag": "v2026.05.05",
  "expected_git_sha": "0123456789abcdef0123456789abcdef01234567",
  "claims": {
    "latest_url_used": true,
    "one_command_server_install": true,
    "installed_git_sha_matches": true,
    "service_active": true,
    "bundle_issue_works": true,
    "target_side_build_not_required": true,
    "source_release_channel": "stable"
  }
}
JSON

cat >"${TMP_DIR}/client/result.json" <<'JSON'
{
  "schema_version": 1,
  "verdict": "PASS",
  "latest_tag": "v2026.05.05",
  "expected_git_sha": "0123456789abcdef0123456789abcdef01234567",
  "claims": {
    "latest_url_used": true,
    "client_bundle_install": true,
    "installed_git_sha_matches": true,
    "service_active": true,
    "socks_listener_active": true,
    "installer_did_not_invoke_cargo_or_rustup": true,
    "source_release_channel": "stable"
  }
}
JSON

cat >"${TMP_DIR}/negative/result.json" <<'JSON'
{
  "schema_version": 1,
  "verdict": "PASS",
  "latest_tag": "v2026.05.05",
  "expected_git_sha": "0123456789abcdef0123456789abcdef01234567",
  "claims": {
    "latest_url_used": true,
    "bad_checksum_rejected": true,
    "unsupported_arch_rejected": true,
    "wrong_expected_git_sha_detected": true
  }
}
JSON

ARTIFACT_DIR="${TMP_DIR}/artifact" \
SERVER_RESULT_JSON="${TMP_DIR}/server/result.json" \
CLIENT_RESULT_JSON="${TMP_DIR}/client/result.json" \
NEGATIVE_RESULT_JSON="${TMP_DIR}/negative/result.json" \
bash "${ROOT_DIR}/scripts/build-release-latest-parity-gate.sh"

grep -q '"status": "RELEASE_LATEST_PARITY_READY"' "${TMP_DIR}/artifact/result.json"
grep -q 'aegis_measure_exit_status=0' "${TMP_DIR}/artifact/commands.txt"
grep -q 'does_not_claim_phase_d_exit=true' "${TMP_DIR}/artifact/environment.txt"

echo "build release latest parity gate contract: PASS"
