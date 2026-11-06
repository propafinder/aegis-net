#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-c-fronted.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cat >"${TMP_DIR}/attempts-pass.jsonl" <<'JSONL'
{"scenario":"normal_fronted_https_ws","status":"PASS","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge.example.test:443","front_transport_scope":"https_ws","origin_relay_address":"198.51.100.22:443"}
{"scenario":"primary_path_blocked","status":"PASS","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge.example.test:443","front_transport_scope":"https_ws","origin_relay_address":"198.51.100.22:443"}
{"scenario":"provider_edge_rotation","status":"PASS","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge2.example.test:443","front_transport_scope":"https_ws","origin_relay_address":"198.51.100.22:443"}
{"scenario":"normal_fronted_https_ws","status":"PASS","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge.example.test:443","front_transport_scope":"https_ws","origin_relay_address":"198.51.100.22:443"}
JSONL

cat >"${TMP_DIR}/provider-doc.md" <<'EOF'
# Fronted HTTP-like Provider Constraints

The provider fronted HTTP-like path must document provider constraints,
supported https_ws transports, allowed fronted authorities, cache behavior, and
operational limits before rollout.
EOF

bash "${ROOT}/scripts/build-phase-c-fronted-transport-evidence.sh" \
  --attempts-jsonl "${TMP_DIR}/attempts-pass.jsonl" \
  --provider-doc "${TMP_DIR}/provider-doc.md" \
  --output-json "${TMP_DIR}/pass.json" \
  --output-markdown "${TMP_DIR}/pass.md"

grep -q '"status": "PASS"' "${TMP_DIR}/pass.json"
grep -q '"fronted_transport_pass_rate": 1.0' "${TMP_DIR}/pass.json"
grep -q '"provider_boundary_evidence": true' "${TMP_DIR}/pass.json"
grep -q 'Phase C Fronted Transport Evidence' "${TMP_DIR}/pass.md"

cat >"${TMP_DIR}/attempts-low-rate.jsonl" <<'JSONL'
{"scenario":"normal_fronted_https_ws","status":"PASS","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge.example.test:443","origin_relay_address":"198.51.100.22:443"}
{"scenario":"primary_path_blocked","status":"PASS","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge.example.test:443","origin_relay_address":"198.51.100.22:443"}
{"scenario":"provider_edge_rotation","status":"FAIL","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge.example.test:443","origin_relay_address":"198.51.100.22:443"}
JSONL

if bash "${ROOT}/scripts/build-phase-c-fronted-transport-evidence.sh" \
  --attempts-jsonl "${TMP_DIR}/attempts-low-rate.jsonl" \
  --provider-doc "${TMP_DIR}/provider-doc.md" \
  --output-json "${TMP_DIR}/low-rate.json"; then
  echo "expected low fronted transport pass rate to block" >&2
  exit 1
fi
grep -q 'fronted_transport_pass_rate_below_0_95' "${TMP_DIR}/low-rate.json"

cat >"${TMP_DIR}/attempts-missing-scenario.jsonl" <<'JSONL'
{"scenario":"normal_fronted_https_ws","status":"PASS","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge.example.test:443","origin_relay_address":"198.51.100.22:443"}
{"scenario":"primary_path_blocked","status":"PASS","provider":"contract-cdn","front_authority":"front.example.test","front_edge_server":"edge.example.test:443","origin_relay_address":"198.51.100.22:443"}
JSONL

if bash "${ROOT}/scripts/build-phase-c-fronted-transport-evidence.sh" \
  --attempts-jsonl "${TMP_DIR}/attempts-missing-scenario.jsonl" \
  --provider-doc "${TMP_DIR}/provider-doc.md" \
  --output-json "${TMP_DIR}/missing-scenario.json"; then
  echo "expected missing adversarial scenario coverage to block" >&2
  exit 1
fi
grep -q 'adversarial_scenario_coverage_missing' "${TMP_DIR}/missing-scenario.json"

cat >"${TMP_DIR}/attempts-self-origin.jsonl" <<'JSONL'
{"scenario":"normal_fronted_https_ws","status":"PASS","provider":"contract-cdn","front_authority":"198.51.100.22","front_edge_server":"198.51.100.22:443","origin_relay_address":"198.51.100.22:443"}
{"scenario":"primary_path_blocked","status":"PASS","provider":"contract-cdn","front_authority":"198.51.100.22","front_edge_server":"198.51.100.22:443","origin_relay_address":"198.51.100.22:443"}
{"scenario":"provider_edge_rotation","status":"PASS","provider":"contract-cdn","front_authority":"198.51.100.22","front_edge_server":"198.51.100.22:443","origin_relay_address":"198.51.100.22:443"}
JSONL

if bash "${ROOT}/scripts/build-phase-c-fronted-transport-evidence.sh" \
  --attempts-jsonl "${TMP_DIR}/attempts-self-origin.jsonl" \
  --provider-doc "${TMP_DIR}/provider-doc.md" \
  --output-json "${TMP_DIR}/self-origin.json"; then
  echo "expected raw-IP/self-origin fronted endpoint to block" >&2
  exit 1
fi
grep -q 'front_authority_raw_ip_or_missing' "${TMP_DIR}/self-origin.json"
grep -q 'fronted_endpoint_matches_origin' "${TMP_DIR}/self-origin.json"

echo "ok"
