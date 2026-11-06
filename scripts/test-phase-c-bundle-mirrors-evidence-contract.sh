#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-c-bundle-mirrors.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

mkdir -p "${TMP_DIR}/bundle/aegis-test"
printf '{"bundle_name":"aegis-test"}\n' >"${TMP_DIR}/bundle/aegis-test/bundle.manifest.json"
printf 'placeholder  bin/aegis-client\n' >"${TMP_DIR}/bundle/aegis-test/SHA256SUMS"
tar -C "${TMP_DIR}/bundle" -czf "${TMP_DIR}/aegis-test.tar.gz" aegis-test
printf 'abc123  aegis-test.tar.gz\n' >"${TMP_DIR}/aegis-test.tar.gz.sha256"

cat >"${TMP_DIR}/primary-blocked.json" <<'JSON'
{
  "status": "BLOCKED",
  "reason": "primary_bundle_host_blocked_by_policy"
}
JSON

cat >"${TMP_DIR}/mirror-pass.json" <<'JSON'
{
  "status": "PASS",
  "mirror_url": "https://mirror.example.test/aegis-test.tar.gz",
  "bundle_sha256": "abc123"
}
JSON

cat >"${TMP_DIR}/voucher-pass.json" <<'JSON'
{
  "status": "PASS",
  "issued_token": true,
  "redeem_once_pass": true,
  "second_redeem_rejected": true,
  "expired_token_rejected": true,
  "revoked_token_rejected": true
}
JSON

cat >"${TMP_DIR}/operator-mirror-voucher.md" <<'EOF'
# Operator Mirror Voucher Runbook

Mirror setup keeps a signed bundle plus checksum on the mirror. Voucher
tokens are one-time, expire, and can be revoked.
EOF

bash "${ROOT}/scripts/build-phase-c-bundle-mirrors-evidence.sh" \
  --primary-fetch-json "${TMP_DIR}/primary-blocked.json" \
  --mirror-fetch-json "${TMP_DIR}/mirror-pass.json" \
  --voucher-flow-json "${TMP_DIR}/voucher-pass.json" \
  --bundle-archive "${TMP_DIR}/aegis-test.tar.gz" \
  --bundle-sha256 "${TMP_DIR}/aegis-test.tar.gz.sha256" \
  --operator-doc "${TMP_DIR}/operator-mirror-voucher.md" \
  --output-json "${TMP_DIR}/pass.json" \
  --output-markdown "${TMP_DIR}/pass.md"

grep -q '"status": "PASS"' "${TMP_DIR}/pass.json"
grep -q '"primary_bundle_host_block_survives": true' "${TMP_DIR}/pass.json"
grep -q '"voucher_expiry_revoke_pass": true' "${TMP_DIR}/pass.json"
grep -q 'Phase C Bundle Mirrors Evidence' "${TMP_DIR}/pass.md"

cat >"${TMP_DIR}/voucher-fail.json" <<'JSON'
{
  "status": "PASS",
  "issued_token": true,
  "redeem_once_pass": true,
  "second_redeem_rejected": false,
  "expired_token_rejected": true,
  "revoked_token_rejected": true
}
JSON

if bash "${ROOT}/scripts/build-phase-c-bundle-mirrors-evidence.sh" \
  --primary-fetch-json "${TMP_DIR}/primary-blocked.json" \
  --mirror-fetch-json "${TMP_DIR}/mirror-pass.json" \
  --voucher-flow-json "${TMP_DIR}/voucher-fail.json" \
  --bundle-archive "${TMP_DIR}/aegis-test.tar.gz" \
  --bundle-sha256 "${TMP_DIR}/aegis-test.tar.gz.sha256" \
  --operator-doc "${TMP_DIR}/operator-mirror-voucher.md" \
  --output-json "${TMP_DIR}/voucher-fail-out.json"; then
  echo "expected failed voucher semantics to block" >&2
  exit 1
fi
grep -q 'voucher_expiry_revoke_not_pass' "${TMP_DIR}/voucher-fail-out.json"

cat >"${TMP_DIR}/mirror-mismatch.json" <<'JSON'
{
  "status": "PASS",
  "mirror_url": "https://mirror.example.test/aegis-test.tar.gz",
  "bundle_sha256": "def456"
}
JSON

if bash "${ROOT}/scripts/build-phase-c-bundle-mirrors-evidence.sh" \
  --primary-fetch-json "${TMP_DIR}/primary-blocked.json" \
  --mirror-fetch-json "${TMP_DIR}/mirror-mismatch.json" \
  --voucher-flow-json "${TMP_DIR}/voucher-pass.json" \
  --bundle-archive "${TMP_DIR}/aegis-test.tar.gz" \
  --bundle-sha256 "${TMP_DIR}/aegis-test.tar.gz.sha256" \
  --operator-doc "${TMP_DIR}/operator-mirror-voucher.md" \
  --output-json "${TMP_DIR}/mirror-fail-out.json"; then
  echo "expected checksum mismatch to block" >&2
  exit 1
fi
grep -q 'signed_bundle_verification_not_preserved' "${TMP_DIR}/mirror-fail-out.json"

echo "ok"
