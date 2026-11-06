#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/server.json" <<'JSON'
{
  "schema_version": 1,
  "artifact": "installer-server-one-command-live",
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

cat >"${TMP_DIR}/client.json" <<'JSON'
{
  "schema_version": 1,
  "artifact": "installer-client-one-command-live",
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

cat >"${TMP_DIR}/negative.json" <<'JSON'
{
  "schema_version": 1,
  "artifact": "installer-negative-live",
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

cargo run -q -p aegis-measure -- release-latest-parity \
  --server-result-json "${TMP_DIR}/server.json" \
  --client-result-json "${TMP_DIR}/client.json" \
  --negative-result-json "${TMP_DIR}/negative.json" \
  --output-json "${TMP_DIR}/result.json" \
  --output-markdown "${TMP_DIR}/result.md"

grep -q '"status": "RELEASE_LATEST_PARITY_READY"' "${TMP_DIR}/result.json"
grep -q '"verdict": "PASS"' "${TMP_DIR}/result.json"
grep -q '"latest_tag_parity": true' "${TMP_DIR}/result.json"
grep -q '"expected_git_sha_parity": true' "${TMP_DIR}/result.json"
grep -q '"stable_channel": true' "${TMP_DIR}/result.json"
grep -q 'Boundary: latest server/client/negative artifact parity only' "${TMP_DIR}/result.md"

sed 's/v2026.05.05/v2026.05.04/' "${TMP_DIR}/client.json" >"${TMP_DIR}/client-bad.json"

if cargo run -q -p aegis-measure -- release-latest-parity \
  --server-result-json "${TMP_DIR}/server.json" \
  --client-result-json "${TMP_DIR}/client-bad.json" \
  --negative-result-json "${TMP_DIR}/negative.json" \
  --output-json "${TMP_DIR}/bad-result.json" \
  --output-markdown "${TMP_DIR}/bad-result.md"; then
  echo "expected release-latest-parity to fail on latest tag mismatch" >&2
  exit 1
fi

grep -q '"status": "RELEASE_LATEST_PARITY_BLOCKED"' "${TMP_DIR}/bad-result.json"
grep -q '"verdict": "NOT_PASS"' "${TMP_DIR}/bad-result.json"
grep -q '"latest_tag_mismatch"' "${TMP_DIR}/bad-result.json"

sed '/latest_tag/d' "${TMP_DIR}/server.json" | sed 's/"artifact": "installer-server-one-command-live"/"artifact": "installer-server-one-command-live",\n  "release_tag": "v2026.05.05"/' >"${TMP_DIR}/server-legacy.json"

cargo run -q -p aegis-measure -- release-latest-parity \
  --server-result-json "${TMP_DIR}/server-legacy.json" \
  --client-result-json "${TMP_DIR}/client.json" \
  --negative-result-json "${TMP_DIR}/negative.json" \
  --output-json "${TMP_DIR}/legacy-result.json"

grep -q '"status": "RELEASE_LATEST_PARITY_READY"' "${TMP_DIR}/legacy-result.json"
grep -q '"latest_tag": "v2026.05.05"' "${TMP_DIR}/legacy-result.json"

echo "release latest parity contract: PASS"
