#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/aegis-phase-b-tls-wire.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

cargo test -p aegis-core parse_phase_b_tls_profile_target_class
cargo test -p aegis-client relay_surface_fields_include_request_shape_variants
cargo test -p aegis-client tls_profile_target_alpn_mapping_covers_primary_transports
cargo test -p aegis-client legacy_tls_wire_alpn_is_opt_in_and_legacy_only
cargo test -p aegis-client tls_wire_adapter_fields_cover_transport_specific_alpn

cat >"${TMP_DIR}/runtime-events-pass.jsonl" <<'JSONL'
{"event_code":"relay_transport_selected","transport":"LegacyTls","relay_surface_tls_profile_target_class":"legacy_tls","relay_surface_tls_profile_target_alpn":["http/1.1"],"relay_surface_tls_wire_adapter":"legacy_tls_target_http11","relay_surface_tls_wire_alpn":["http/1.1"]}
{"event_code":"relay_session_succeeded","chosen_transport":"HttpsWs","relay_surface_tls_profile_target_class":"https_ws","relay_surface_tls_profile_target_alpn":["h2","http/1.1"],"relay_surface_tls_wire_adapter":"websocket_http1_fixed","relay_surface_tls_wire_alpn":["http/1.1"]}
{"event_code":"relay_transport_failed","transport":"MasqueDerived","relay_surface_tls_profile_target_class":"masque_derived","relay_surface_tls_profile_target_alpn":["h3","masque"],"relay_surface_tls_wire_adapter":"masque_h3_fixed","relay_surface_tls_wire_alpn":["h3"]}
JSONL

cargo run -q -p aegis-measure -- phase-b-tls-wire-review \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events-pass.jsonl" \
  --output-json "${TMP_DIR}/tls-wire-review-pass.json" \
  --output-markdown "${TMP_DIR}/tls-wire-review-pass.md"
grep -q '"status": "PASS"' "${TMP_DIR}/tls-wire-review-pass.json"
grep -q 'Phase B TLS Wire Review' "${TMP_DIR}/tls-wire-review-pass.md"

cat >"${TMP_DIR}/runtime-events-fail.jsonl" <<'JSONL'
{"event_code":"relay_session_succeeded","chosen_transport":"HttpsWs","relay_surface_tls_profile_target_class":"https_ws","relay_surface_tls_profile_target_alpn":["h2"],"relay_surface_tls_wire_adapter":"websocket_http1_fixed","relay_surface_tls_wire_alpn":["http/1.1"]}
JSONL

if cargo run -q -p aegis-measure -- phase-b-tls-wire-review \
  --runtime-events-jsonl "${TMP_DIR}/runtime-events-fail.jsonl" \
  --output-json "${TMP_DIR}/tls-wire-review-fail.json" >/dev/null 2>&1; then
  echo "expected Phase B TLS wire target mismatch failure" >&2
  exit 1
fi
grep -q '"status": "FAIL"' "${TMP_DIR}/tls-wire-review-fail.json"

echo "PASS: Phase B TLS profile target contract"
