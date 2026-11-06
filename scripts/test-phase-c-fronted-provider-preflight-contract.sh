#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-c-fronted-preflight.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

provider_doc="${TMP_DIR}/fronted-provider-constraints.md"
cat >"${provider_doc}" <<'EOF'
# Provider Constraints

The provider fronted MASQUE contour documents provider constraints, allowed
fronted authorities, cache behavior, and operational limits.
EOF

bash "${ROOT}/scripts/build-phase-c-fronted-provider-preflight.sh" \
  --front-authority front.example.test \
  --front-masque-server edge.example.test:443 \
  --origin-relay-address 198.51.100.22:443 \
  --provider-doc "${provider_doc}" \
  --output-json "${TMP_DIR}/pass.json" \
  --output-markdown "${TMP_DIR}/pass.md"

grep -q '"status": "PASS"' "${TMP_DIR}/pass.json"
grep -q '"front_authority_not_raw_ip": true' "${TMP_DIR}/pass.json"
grep -q '"fronted_endpoint_not_origin": true' "${TMP_DIR}/pass.json"
grep -q 'Phase C Fronted Provider Preflight' "${TMP_DIR}/pass.md"

if bash "${ROOT}/scripts/build-phase-c-fronted-provider-preflight.sh" \
  --front-authority 198.51.100.22 \
  --front-masque-server 198.51.100.22:443 \
  --origin-relay-address 198.51.100.22:443 \
  --provider-doc "${provider_doc}" \
  --output-json "${TMP_DIR}/self-origin.json"; then
  echo "expected raw-IP same-origin fronted provider preflight to fail" >&2
  exit 1
fi
grep -q 'front_authority_raw_ip_or_missing' "${TMP_DIR}/self-origin.json"
grep -q 'fronted_endpoint_matches_origin' "${TMP_DIR}/self-origin.json"

if bash "${ROOT}/scripts/build-phase-c-fronted-provider-preflight.sh" \
  --front-authority '<provider-fronted-authority>' \
  --front-masque-server '<provider-edge-host:443>' \
  --origin-relay-address '<origin-relay-host:443>' \
  --provider-doc "${provider_doc}" \
  --output-json "${TMP_DIR}/placeholder.json"; then
  echo "expected placeholder fronted provider preflight to fail" >&2
  exit 1
fi
grep -q 'front_authority_placeholder_value' "${TMP_DIR}/placeholder.json"
grep -q 'front_masque_server_placeholder_value' "${TMP_DIR}/placeholder.json"
grep -q 'origin_relay_address_placeholder_value' "${TMP_DIR}/placeholder.json"

cat >"${TMP_DIR}/weak-provider-doc.md" <<'EOF'
# Notes

No provider constraints are documented here.
EOF

if bash "${ROOT}/scripts/build-phase-c-fronted-provider-preflight.sh" \
  --front-authority front.example.test \
  --front-masque-server edge.example.test:443 \
  --origin-relay-address 198.51.100.22:443 \
  --provider-doc "${TMP_DIR}/weak-provider-doc.md" \
  --output-json "${TMP_DIR}/weak-doc.json"; then
  echo "expected weak provider constraints doc to fail" >&2
  exit 1
fi
grep -q 'operator_provider_constraints_not_documented' "${TMP_DIR}/weak-doc.json"

echo "ok"
